package org.javelus.minitrace.android;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;

/**
 * 
 * Thread ID: u2
 * Method ID: u4
 * Field ID:  u4
 * Object ID: u4
 * DexPC:     u4
 * Record Size:
 *   Method Event: ThreadID + MethodID = 6
 *   Field Event: ThreadID + FieldID + ObjectID + DexPC =  14
 *   Monitor Event: ThreadID + ObjectID + DexPC = 10
 * @author t
 *
 */
public class MiniTrace {

    enum Section {
        THREADS("([0-9]+)\t(.+)"), 
        METHODS("0x([0-9A-Za-z]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)"), 
        FIELDS("0x([0-9A-Za-z]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)"), 
        EXECUTION_DATA("0x([0-9A-Za-z]+)\t([0-9]+)\t([01]+)");

        private Pattern pattern;

        Section(String pattern) {
            this.pattern = Pattern.compile(pattern);
        }

        public Matcher match(String line) {
            return pattern.matcher(line);
        }
    };

    public static MiniTrace load(String fileName) throws IOException {
        Map<Integer, MemberMeta> methods = new HashMap<Integer, MemberMeta>();
        Map<Integer, MemberMeta> fields = new HashMap<Integer, MemberMeta>();
        Map<Integer, String> threads = new HashMap<Integer, String>();
        Map<MemberMeta, String> methodData = new HashMap<MemberMeta, String>();

        BufferedReader br = null;

        try {
            br = new BufferedReader(new FileReader(fileName));
            String line = null;
            Section section = null;
            while ((line = br.readLine()) != null) {
                if (line.charAt(0) == '*') {
                    if (line.equals("*end")) {
                        break;
                    }
                    if (line.equals("*threads")) {
                        section = Section.THREADS;
                    } else if (line.equals("*methods")) {
                        section = Section.METHODS;
                    } else if (line.equals("*fields")) {
                        section = Section.FIELDS;
                    } else if (line.equals("*coverage")) {
                        section = Section.EXECUTION_DATA;
                    }
                    continue;
                }

                if (section == null) {
                    throw new RuntimeException("Illegal file format!");
                }

                switch (section) {
                case THREADS: {
                    Matcher m = Section.THREADS.match(line);
                    if (m.matches()) {
                        Integer id = Integer.parseInt(m.group(1));
                        String name = m.group(2);
                        threads.put(id, name);
                    } else {
                        throw new RuntimeException("Cannot match thread line " + line);
                    }
                    break;} 
                case METHODS:{
                    Matcher m = Section.METHODS.match(line);
                    if (m.matches()) {
                        Integer id = Integer.parseInt(m.group(1), 16);
                        String className = m.group(2);
                        String name = m.group(3);
                        String desc = m.group(4);
                        methods.put(id, new MemberMeta(className, name, desc));
                    } else {
                        throw new RuntimeException("Cannot method thread line " + line);
                    }
                    break;}
                case FIELDS:{
                    Matcher m = Section.FIELDS.match(line);
                    if (m.matches()) {
                        Integer id = Integer.parseInt(m.group(1), 16);
                        String className = m.group(2);
                        String name = m.group(3);
                        String desc = m.group(4);
                        fields.put(id, new MemberMeta(className, name, desc));
                    } else {
                        throw new RuntimeException("Cannot method thread line " + line);
                    }
                    break;}
                case EXECUTION_DATA:{
                    Matcher m = Section.EXECUTION_DATA.match(line);
                    if (m.matches()) {
                        Integer id = Integer.parseInt(m.group(1), 16);
                        MemberMeta method = methods.get(id);
                        if (method == null) {
                            throw new RuntimeException("Invalid method id " + id);
                        }
                        Integer length = Integer.parseInt(m.group(2));
                        String data = m.group(3);
                        if (data.length() != length) {
                            throw new RuntimeException("Invalid");
                        }
                        methodData.put(method, data);
                    } else {
                        throw new RuntimeException("Cannot method thread line " + line);
                    }
                    break;}
                }
            }
        } finally {
            if (br != null) {
                br.close();
            }
        }

        return new MiniTrace(methods, fields, threads, methodData);
    }
    
    private Map<Integer, MemberMeta> methods;
    private Map<Integer, MemberMeta> fields;
    private Map<Integer, String> threads;
    private Map<MemberMeta, String> methodData;

    public MiniTrace(Map<Integer, MemberMeta> methods,
            Map<Integer, MemberMeta> fields, Map<Integer, String> threads,
            Map<MemberMeta, String> methodData) {
        super();
        this.methods = methods;
        this.fields = fields;
        this.threads = threads;
        this.methodData = methodData;
    }

    public MemberMeta getMethod(int methodId) {
        return methods.get(methodId);
    }
    
    public MemberMeta getField(int fieldId) {
        return fields.get(fieldId);
    }
    
    public Map<Integer, MemberMeta> getMethods() {
        return methods;
    }

    public Map<Integer, MemberMeta> getFields() {
        return fields;
    }

    public Map<Integer, String> getThreads() {
        return threads;
    }

    public Map<MemberMeta, String> getMethodData() {
        return methodData;
    }

//    public void dumpCoverageFromAPK(File apkFile) throws IOException {
//        System.out.println("Checking APK file: " + apkFile);
//        DexFile dexFile = DexFileFactory.loadDexFile(apkFile, "classes.dex", 19 /*api level*/, false);
//        dumpCoverage(dexFile);
//    }
//    
//    public void dumpCoverageFromDex(File file) throws IOException {
//        System.out.println("Checking dex file: " + file);
//        DexFile dexFile = DexFileFactory.loadDexFile(file, 19, false);
//        dumpCoverage(dexFile);
//    }
//    
    public void dumpCoverage(DexFile dexFile) {
        for (ClassDef classDef: dexFile.getClasses()) {
            for (Method method:classDef.getMethods()) {
                if (method.getImplementation() != null) {
                    MemberMeta mm = new MemberMeta(Utils.binaryNameToName(method.getDefiningClass()), method.getName(), 
                            Utils.getDescriptor(method.getParameterTypes(), method.getReturnType()));
                    
                    String data = this.methodData.get(mm);
                    
                    if (data == null) {
                        continue;
                    }
                    
                    int pc = 0;
                    int total = 0;
                    int covered = 0;
                    for (Instruction insn:method.getImplementation().getInstructions()) {
                        if (data.charAt(pc) == '1') {
                            covered++;
                        }
                        total++;
                        pc += insn.getCodeUnits();
                    }
                    if (pc != data.length()) {
                        throw new RuntimeException("Sanity check failed!");
                    }
                    System.out.println("Coverage of " + mm + ": " + covered + "/" + total + "(" + (float)covered/total + ")");
                }
            }
        }
    
    }
    
    public void dumpData(String dataFilename) throws IOException {
        TraceEventStream stream = null;
        try {
            stream = new TraceEventStream((dataFilename));
            TraceEvent event = null;
            while ((event = stream.nextEvent(this)) != null) {
                System.out.println(event);
            }
        } finally {
            if (stream != null) {
                stream.close();
            }
        }
    }
}