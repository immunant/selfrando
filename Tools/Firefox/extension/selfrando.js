Components.utils.import("resource://gre/modules/ctypes.jsm");
Components.utils.import("resource://gre/modules/osfile.jsm");

const RGBA_START = [255, 255, 255, 255];
const RGBA_END   = [  0,   0, 255, 255];
const PLOT_HEIGHT = 512;
const PLOT_WIDTH = 200;
const MAX_PLOT_FUNCTIONS = 1000000;

function plot_mapping(canvas, mapping) {
    if (mapping.length != PLOT_HEIGHT)
        throw new Error("Invalid length for mapping array!");

    canvas.width = PLOT_WIDTH;
    canvas.height = PLOT_HEIGHT;
    let ctx = canvas.getContext('2d');
    let img = ctx.createImageData(PLOT_WIDTH, PLOT_HEIGHT);
    let idx = 0;
    for (let i = 0; i < PLOT_HEIGHT; i++) {
        let im = mapping[i];
        let icols = [0, 1, 2, 3].map(k => RGBA_START[k] + Math.floor((RGBA_END[k] - RGBA_START[k]) * im / PLOT_HEIGHT));
        for (let j = 0; j < PLOT_WIDTH; j++)
            for (let k = 0; k < 4; k++)
                img.data[idx++] = icols[k];
    }
    ctx.putImageData(img, 0, 0);
}

function draw_modules(modules) {
    let sr_box = document.getElementById("selfrando-box");
    console.log("Modules:" + modules.length);
    for (let module of modules) {
        console.log("Version:" + module.version.toString(16) + " seed:" + module.seed.toString(16));
        console.log("Module@" + module.file_base.toString(16) +
                    " funcs@" + module.func_base.toString(16) +
                    "[" + module.func_size.toString() + "]");
        console.log("Module:'" + module.name + "'");
        console.log("Functions:" + module.functions.length);
        if (module.functions.length > MAX_PLOT_FUNCTIONS) {
            console.log("Module has too many functions, ignoring...");
            continue;
        }

        let undiv_mapping = Array.from(Array(PLOT_HEIGHT).keys());
        let div_mapping = Array.from(Array(PLOT_HEIGHT).keys());
        let plot_step = Math.floor(module.func_size / PLOT_HEIGHT);
        console.log("Plot step:" + plot_step);
        for (let i = 0, func = 0, addr = module.func_base;
             i < PLOT_HEIGHT; i++, addr += plot_step) {
            // We rely on the function list being sorted by div_start
            while (func < module.functions.length) {
                let func_end = module.functions[func].div_start + module.functions[func].size;
                if (addr < func_end)
                    break;
                func++;
            }
            if (func == module.functions.length)
                break;
            if (addr >= module.functions[func].div_start) {
                // We found a function for this address, add it to the mapping
                let div_delta = addr - module.functions[func].div_start;
                let undiv_addr = module.functions[func].undiv_start + div_delta;
                div_mapping[i] = Math.floor((undiv_addr - module.func_base) / plot_step);
            }
        }

        let xul_module = document.createElement("selfrando-module");
        sr_box.appendChild(xul_module);
        xul_module.set_module_data(module);
        plot_mapping(xul_module.undiv_canvas, undiv_mapping);
        plot_mapping(xul_module.div_canvas, div_mapping);
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
        return res >>> 0;
    }

    // Small hack we do here: JavaScript numbers can accurately store 53-bit integers,
    // and in most cases that's all we need for pointers (due to x86_64 architecture design)
    let is_64bit = ctypes.intptr_t.size == ctypes.int64_t.size;
    function read_ptr() {
        let lo = read_uint32();
        if (is_64bit) {
            let hi = read_uint32();
            if (hi >= (1 << 21))
                throw new Error("Pointer value does not fit in JavaScript Number");
            return hi * Math.pow(2, 32) + lo;
        }
        return lo;
    }

    // FIXME: Windows actually emits ANSI, but UTF-8 is the closest thing we have
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
