package org.javelus.minitrace.android.coverage;

import java.io.File;
import java.io.IOException;
import java.util.List;

public interface DataParser {
    List<Data> parse(File file) throws IOException;
}
