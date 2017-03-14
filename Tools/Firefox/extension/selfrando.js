Components.utils.import("resource://gre/modules/ctypes.jsm");
Components.utils.import("resource://gre/modules/OSFile.jsm");

// FIXME: add a Linux version of this
let kernel32 = ctypes.open("kernel32.dll");
let GetCurrentProcessId = kernel32.declare("GetCurrentProcessId", ctypes.winapi_abi, ctypes.uint32_t);
let pid = GetCurrentProcessId();
console.log('Firefox PID: ' + pid);

let mlf_path = OS.Constants.Path.tmpDir;
let mlf_file = OS.Path.join(mlf_path, pid + '.mlf');
console.log("Selfrando layout file: " + mlf_file);

function read_mlf_file(file_data) {
    console.log("Successfully read layout file!");
    let file_vals = new DataView(file_data.buffer);
    let idx = 0;

    function read_uint32() {
        let res = file_vals.getUint32(idx, true);
        idx += 4;
        return ctypes.UInt64(res);
    }

    let is_64bit = ctypes.intptr_t.size == ctypes.int64_t.size;
    function read_ptr() {
        let lo = read_uint32();
        let hi = 0;
        if (is_64bit)
            hi = read_uint32();
        return ctypes.UInt64.join(hi, lo);
    }

    let utf8_decoder = new TextDecoder('utf-8');
    function read_string() {
        let name_start = idx;
        while (file_data[idx] != 0)
            idx++;
        let res = utf8_decoder.decode(file_data.subarray(name_start, idx));
        idx++; // Advance past the null terminator
        return res;
    }

    while (idx < file_data.length) {
        let version = read_uint32();
        let seed = read_uint32();
        console.log("Version:" + version.toString(16) + " seed:" + seed.toString(16));

        let file_base = read_ptr();
        let func_base = read_ptr();
        let func_size = read_ptr();
        console.log("Module@" + file_base.toString(16) +
                    " funcs@" + func_base.toString(16) +
                    "[" + func_size.toString() + "]");

        let module_name = read_string();
        console.log("Module:'" + module_name + "'");

        let num_funcs = 0;
        for (; ;) {
            let undiv_start = read_ptr();
            if (undiv_start == 0)
                break;
            let div_start = read_ptr();
            let undiv_size = read_uint32();
            num_funcs++;
            //console.log("Func@" + undiv_start.toString(16) +
            //            "[" + undiv_size.toString() + "]" +
            //            "=>" + div_start.toString(16));
        }
        console.log("Functions:" + num_funcs);
    }
}
let mlf_promise = OS.File.read(mlf_file, { read: true, write: false, existing: true });
mlf_promise.then(read_mlf_file, function (error) { console.log('Error reading layout file: ' + error) });
