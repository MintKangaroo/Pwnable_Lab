// Ghidra headless post-script (Java): decompile functions to JSON.
// Args: [output_json_path] [max_functions]
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

public class DecompileToJson extends GhidraScript {
    private static String esc(String s) {
        if (s == null) return null;
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }
    private static String q(String s) { return s == null ? "null" : "\"" + esc(s) + "\""; }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = args.length > 0 ? args[0] : "/tmp/ghidra_out.json";
        int maxF = args.length > 1 ? Integer.parseInt(args[1]) : 200;

        DecompInterface d = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        d.setOptions(opts);
        d.toggleCCode(true);
        d.toggleSyntaxTree(true);
        d.setSimplificationStyle("decompile");
        d.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        FunctionManager fm = currentProgram.getFunctionManager();

        List<String> recs = new ArrayList<>();
        int count = 0;
        for (Function f : fm.getFunctions(true)) {
            if (count >= maxF) break;
            if (f.isExternal() || f.isThunk()) continue;
            String c = null;
            try {
                DecompileResults r = d.decompileFunction(f, 60, mon);
                if (r != null && r.decompileCompleted())
                    c = r.getDecompiledFunction().getC();
                else if (r != null)
                    println("decompile fail " + f.getName() + ": " + r.getErrorMessage());
            } catch (Exception e) { println("decompile exc " + f.getName() + ": " + e); }
            StringBuilder rec = new StringBuilder();
            rec.append("{\"name\":").append(q(f.getName()));
            rec.append(",\"entry\":\"0x").append(Long.toHexString(f.getEntryPoint().getOffset())).append("\"");
            rec.append(",\"signature\":").append(q(f.getPrototypeString(false, false)));
            rec.append(",\"c\":").append(q(c)).append("}");
            recs.add(rec.toString());
            count++;
        }
        StringBuilder j = new StringBuilder();
        j.append("{\"program\":").append(q(currentProgram.getName()));
        j.append(",\"language\":").append(q(currentProgram.getLanguageID().toString()));
        j.append(",\"image_base\":\"0x").append(Long.toHexString(currentProgram.getImageBase().getOffset())).append("\"");
        j.append(",\"function_count\":").append(count);
        j.append(",\"functions\":[");
        for (int i = 0; i < recs.size(); i++) { if (i>0) j.append(","); j.append(recs.get(i)); }
        j.append("]}");
        try (FileWriter w = new FileWriter(out)) { w.write(j.toString()); }
        println("[DecompileToJson] wrote " + count + " functions to " + out);
    }
}
