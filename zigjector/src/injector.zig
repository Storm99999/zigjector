//////////////////////////////// ZIGJECTOR  ///////////////////////////////////
///                                                                        ///
///   Zigjector, written by newguy - 2023, 13th Nov.                      ///
///                                                                      ///
///   Zigjector is a powerful and lightning fast DLL Injector           ///
///                                                                    ///
///                                                                   ///
///   Free to use in any of your future projects!                    ///
///////////////////////////////////////////////////////////////////////

const std = @import("std");
const win32 = @cImport({
    @cInclude("windows.h");
});

pub fn inject_dll(process_id: u32, dll_path: []const u8) anyerror!void {
    const PROCESS_CREATE_THREAD = 0x0002;
    const PROCESS_QUERY_INFORMATION = 0x0400;
    const PROCESS_VM_OPERATION = 0x0008;
    const PROCESS_VM_WRITE = 0x0020;
    const PROCESS_VM_READ = 0x0010;
    const MEM_COMMIT = 0x1000;
    const MEM_RESERVE = 0x2000;
    const PAGE_READWRITE = 0x04;

    var h_process: win32.HANDLE = undefined;
    h_process = win32.OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, process_id);

    if (h_process == null) {
        std.debug.print("Failed to open process. Error code: {}\n", .{win32.GetLastError()});
        return;
    }

    const proc_address = win32.GetProcAddress(win32.GetModuleHandle(null), "LoadLibraryA");

    var int_ptr: win32.LPVOID = undefined;
    int_ptr = win32.VirtualAllocEx(h_process, null, @intCast(std.mem.len(dll_path) + 1), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (int_ptr == null) {
        std.debug.print("Failed to allocate memory in the remote process. Error code: {}\n", .{win32.GetLastError()});
        win32.CloseHandle(h_process);
        return;
    }

    var bytes_written: win32.SIZE_T = undefined;
    if (!win32.WriteProcessMemory(h_process, int_ptr, dll_path, std.mem.len(dll_path) + 1, &bytes_written)) {
        std.debug.print("Failed to write DLL path to remote process memory. Error code: {}\n", .{win32.GetLastError()});
        win32.CloseHandle(h_process);
        return;
    }

    const h_thread = win32.CreateRemoteThread(h_process, null, 0, proc_address, int_ptr, 0, null);

    if (h_thread == null) {
        std.debug.print("Failed to create remote thread. Error code: {}\n", .{win32.GetLastError()});
        win32.CloseHandle(h_process);
        return;
    }

    std.debug.print("DLL injected successfully.\n");

    // Clean up
    win32.CloseHandle(h_thread);
    win32.CloseHandle(h_process);
}

pub fn main() anyerror!void {
    const args = std.process.args();
    if (args.len != 3) {
        std.debug.print("Usage: {} <ProcessID> <DLLPath>\n", .{args[0]});
        return;
    }

    const process_id = try args[1].parseInt(u32) catch unreachable;
    const dll_path = args[2].idup();
    inject_dll(process_id, dll_path);
}
