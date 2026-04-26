var metadata = {
    name: "Execution-BOF",
    description: "Windows Execution BOFs"
};

var cmd_run_sc = ax.create_command("runsc", "Execute x64 shellcode in memory", "runsc <path>");
cmd_run_sc.addArgFile("path", true, "Path to shellcode.bin");
cmd_run_sc.addArgBool( "--userwx", false , "Alloc RWX memory");
cmd_run_sc.addArgBool( "--nopipe", false , "Shellcode I/O with anonymous pipe");
cmd_run_sc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let use_rwx = 0;
    let no_pipe = 0;
    let shellcode_content = parsed_json["path"];
    if(parsed_json["--userwx"]) { use_rwx = 1; }
    if(parsed_json["--nopipe"]) { no_pipe = 1; }
    let bof_params = ax.bof_pack("bytes,int,int",[shellcode_content,use_rwx,no_pipe]);
    
    let bof_path = ax.script_dir() + "run_sc/_bin/runsc.x64.o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Execute shellcode in memroy");
});

var group_test = ax.create_commands_group("Execution-BOF", [cmd_run_sc]);
ax.register_commands_group(group_test, ["beacon", "gopher", "kharon"], ["windows"], []);
