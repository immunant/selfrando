Components.utils.import("resource://gre/modules/ctypes.jsm");

var kernel32 = ctypes.open("kernel32.dll");

var GetCurrentProcessId = kernel32.declare("GetCurrentProcessId", ctypes.winapi_abi, ctypes.uint32_t);

var pid = GetCurrentProcessId();

var sr_wnd = document.getElementById("selfrando-window");
var pid_text = document.createElement("label");
pid_text.setAttribute("value", "Firefox process PID: " + pid);
sr_wnd.appendChild(pid_text);
