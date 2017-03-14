Components.utils.import("resource://gre/modules/ctypes.jsm");
Components.utils.import("resource://gre/modules/OSFile.jsm");

const START_RGBA = [255, 255, 255, 255];
const   END_RGBA = [0, 0, 255, 255];

function draw_modules(modules) {
    console.log("Modules:" + modules.length);
    for (let module of modules) {
        console.log("Version:" + module.version.toString(16) + " seed:" + module.seed.toString(16));
        console.log("Module@" + module.file_base.toString(16) +
                    " funcs@" + module.func_base.toString(16) +
                    "[" + module.func_size.toString() + "]");
        console.log("Module:'" + module.name + "'");
        console.log("Functions:" + module.functions.length);
        for (let func of module.functions) {
            //console.log("Func@" + func.undiv_start.toString(16) +
            //            "[" + func.size.toString() + "]" +
            //            "=>" + func.div_start.toString(16));
        }
    }
}

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

    let modules = [];
    while (idx < file_data.length) {
        module = {};
        module.version = read_uint32();
        module.seed = read_uint32();
        module.file_base = read_ptr();
        module.func_base = read_ptr();
        module.func_size = read_ptr();
        module.name = read_string();
        module.functions = [];
        for (;;) {
            let func = {};
            func.undiv_start = read_ptr();
            if (func.undiv_start == 0)
                break;
            func.div_start = read_ptr();
            func.size = read_uint32();
            module.functions.push(func);
        }
        modules.push(module);
    }
    draw_modules(modules);
}
let mlf_promise = OS.File.read(mlf_file, { read: true, write: false, existing: true });
mlf_promise.then(read_mlf_file, function (error) { console.log('Error reading layout file: ' + error) });
