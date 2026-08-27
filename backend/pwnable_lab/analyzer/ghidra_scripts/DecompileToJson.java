// Ghidra headless post-script (Java): decompile functions to JSON.
// Args: [output_json_path] [max_functions]
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
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
            // 스택 프레임 레이아웃: 각 지역/파라미터의 프레임 오프셋과 크기.
            // 오버플로 버퍼에서 저장된 반환 주소까지의 거리(= payload 오프셋) 계산에 쓴다.
            StringBuilder vars = new StringBuilder("[");
            int retOff = 0;
            boolean haveRet = false;
            try {
                StackFrame frame = f.getStackFrame();
                if (frame != null) {
                    retOff = frame.getReturnAddressOffset();
                    haveRet = true;
                    boolean first = true;
                    for (Variable v : frame.getStackVariables()) {
                        if (!first) vars.append(",");
                        first = false;
                        int len = v.getLength();
                        String dt = v.getDataType() != null ? v.getDataType().getName() : null;
                        vars.append("{\"name\":").append(q(v.getName()));
                        vars.append(",\"offset\":").append(v.getStackOffset());
                        vars.append(",\"size\":").append(len);
                        vars.append(",\"type\":").append(q(dt)).append("}");
                    }
                }
            } catch (Exception e) { /* 프레임 없음/스트립 등 */ }
            vars.append("]");

            StringBuilder rec = new StringBuilder();
            rec.append("{\"name\":").append(q(f.getName()));
            rec.append(",\"entry\":\"0x").append(Long.toHexString(f.getEntryPoint().getOffset())).append("\"");
            rec.append(",\"signature\":").append(q(f.getPrototypeString(false, false)));
            rec.append(",\"c\":").append(q(c));
            if (haveRet) rec.append(",\"return_addr_offset\":").append(retOff);
            rec.append(",\"stack_vars\":").append(vars.toString()).append("}");
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
