/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <cstdlib>
#include <cstring>
#include <ctype.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>

#include <algorithm>
#include <list>
#include <map>
#include <set>
#include <stack>
#include <vector>

#include <Object.h>
#include <Debug.h>
#include <Filesystem.h>
#include <Misc.h>

namespace {

static const char kProgramInfoTableName[] = "_TRaP_ProgramInfoTable";
static const char kInitEntryPointName[] = "_TRaP_selfrando_init";
static const char kStartEntryPointName[] = "_TRaP_selfrando_entry";
static const char kTextrampAnchorName[] = "_TRaP_textramp_anchor";

// This is the name of the built executable. Used to determine if we are
// invoking a wrapper and passing it the real linker as the first argument or if
// this program should transparently pretend to be the linker.
static const char kLinkerWrapperName[] = "traplinker";

static const char kLinkerPathVariable[] = "SELFRANDO_ORIGINAL_LINKER";

// Path to script that identifies the linker type (BFD or GOLD)
static char kLinkerIdScript[] = "/traplinker_id.sh";

// FOR TESTING! TODO: figure out a better way to find this path
static char kSelfrandoObject[] = "/selfrando_txtrp.o";
static char kTrapScript[] = "/traplinker_script.ld";
#if 0 // FIXME: put this back in when we need it
static const char *kExecSections[][2] = {
    { ".text", ".txtrp" }, // FIXME: ".trap.text" would be nicer
    { ".plt", ".trap.plt" }
};
#endif

#ifdef EM_AARCH64
static_assert(EM_AARCH64 == 183, "Invalid value for EM_AARCH64");
#endif
static const std::unordered_map<uint16_t, const char*> kELFMachineNames = {
    { EM_386,       "x86"    },
    { EM_X86_64,    "x86_64" },
    { EM_ARM,       "arm"    },
    { 183,          "arm64"  }, // EM_AARCH64 == 183
};

typedef std::tuple<std::vector<char*>, bool, bool> LinkerInvocation;

class ArgParser {
public:
    ArgParser(int argc, char* argv[]) : m_argc(argc), m_argv(argv),
                                        m_enabled(true), m_relocatable(false),
                                        m_shared(false), m_static(false),
                                        m_whole_archive(false),
                                        m_sysroot(), m_canonical_sysroot() {
        m_output_file = std::string("a.out");
        m_entry_point = "_start";
        m_dt_init = "_init";
    }

    bool parse();

    bool is_trap_enabled() const {
        return m_enabled && !m_relocatable;
    }

    bool emit_textramp() const {
        return m_emit_textramp;
    }

    bool emit_eh_txtrp() const {
        return m_emit_eh_txtrp;
    }

    std::vector<std::pair<std::string, bool>> input_files() const {
        return m_input_files;
    }

    std::string output_file() const {
        return m_output_file;
    }

    const std::string &canonical_sysroot() const {
        return m_canonical_sysroot;
    }

    const std::string &ar_path() const {
        return m_original_ar_path;
    }

    void change_option(std::string option, std::string value, bool single_arg);

    LinkerInvocation create_new_invocation(std::map<std::string, std::string> input_file_mapping,
                                           uint16_t elf_machine);

    std::pair<std::string, std::string> get_entry_point_names();

    enum LibResult {
        NOT_FOUND,
        FOUND_SHARED_LIB,
        FOUND_STATIC_LIB
    };

    LibResult find_library(std::string &libName, std::string &fullPath);

private:
    enum LinkerType {
        LD_UNKNOWN = 0,
        LD_BFD = 1,
        LD_GOLD = 2,
    };

    bool is_linker_replacement();

    int get_value(int i, const std::string &arg_key, std::string &val);
    int handle_input_file(int i);

#define HANDLE_OPTION_BOOL(opt, defval)                     \
    bool m_ ## opt = (defval);                              \
    int handle_ ## opt(int i, const std::string &arg_key) { \
        m_ ## opt = !(defval);                              \
        return 0;                                           \
    }

    int handle_output(int i, const std::string &arg_key);
    int handle_entry(int i, const std::string &arg_key);
    int handle_init(int i, const std::string &arg_key);
    int handle_library(int i, const std::string &arg_key);
    int handle_library_path(int i, const std::string &arg_key);
    int handle_shared(int i, const std::string &arg_key);
    int handle_static(int i, const std::string &arg_key);
    int handle_dynamic(int i, const std::string &arg_key);
    int handle_relocatable(int i, const std::string &arg_key);
    int handle_push_state(int i, const std::string &arg_key);
    int handle_pop_state(int i, const std::string &arg_key);
    int handle_z_keyword(int i, const std::string &arg_key);
    int handle_whole_archive(int i, const std::string &arg_key);
    int handle_sysroot(int i, const std::string &arg_key);

    int handle_original_linker(int i, const std::string &arg_key);
    int handle_original_ar(int i, const std::string &arg_key);
    int handle_traplinker_disable(int i, const std::string &arg_key);
    int handle_traplinker_enable(int i, const std::string &arg_key);
    HANDLE_OPTION_BOOL(static_selfrando,        false);
    HANDLE_OPTION_BOOL(selfrando_txtrp_pages,   false);
    HANDLE_OPTION_BOOL(add_selfrando_libs,      true);
    HANDLE_OPTION_BOOL(emit_textramp,           true);
    HANDLE_OPTION_BOOL(pic_warning,             true);
    HANDLE_OPTION_BOOL(emit_eh_txtrp,           false);
    HANDLE_OPTION_BOOL(hook_init,               true);
    HANDLE_OPTION_BOOL(hook_entry,              true);
    HANDLE_OPTION_BOOL(link_libdl,              true);

    int ignore_arg(int i, const std::string &arg_key);
    int ignore_arg_with_value(int i, const std::string &arg_key);
    int ignore_short_arg_with_value(int i, const std::string &arg_key);
    int ignore_long_arg_with_value(int i, const std::string &arg_key);
    int ignore_arg_with_optional_value(int i, const std::string &arg_key);

    // Argument to pass to linker, but that also disables randomization,
    // e.g., --help or --version
    int ignore_arg_disable_rando(int i, const std::string &arg_key);

    int m_argc;
    char **m_argv;

    struct Arg {
        // Either a file or option argument (depending on is_option)
        Arg(const char *arg, bool is_option = false) : arg(arg), is_option(is_option) {}

        // Option argument
        Arg(char * const *argv, unsigned num_args) : is_option(true) {
            assert(num_args <= 2);
            arg = argv[0];
            if (num_args == 2)
                value = argv[1];
        }

        bool operator< (const Arg& a) const {
            if (arg < a.arg)
                return true;
            if (value < a.value)
                return true;
            return false;
        }

        std::string arg;
        std::string value;
        bool is_option;
    };
    std::list<Arg> m_args;

    std::string m_output_file;
    std::string m_entry_point;
    std::string m_dt_init;
    std::vector<std::pair<std::string, bool>> m_input_files;

    std::vector<std::string> m_library_paths;
    std::map<Arg, std::string> m_system_libs;

    std::set<std::string> m_z_keywords;

    std::string m_original_linker_path;
    std::string m_original_ar_path;
    bool m_enabled;

    bool m_relocatable;
    bool m_shared;
    bool m_static;
    std::stack<bool> m_static_stack;

    bool m_whole_archive;

    std::string m_sysroot;
    std::string m_canonical_sysroot;

    static std::map<std::string, int (ArgParser::*)(int, const std::string&) > m_arg_table;
};

#include "LinkerOptions.inc"

class LinkerScript {
public:
    LinkerScript(int fd, bool is_in_sysroot, const std::string &canonical_sysroot);
    std::vector<std::string> referenced_files() {
        std::vector<std::string> files;
        for (auto file_pair : m_referenced_files) {
	    files.push_back(file_pair.first);
        }
        return files;
    }
    std::vector<std::string> search_dirs() {
        return m_searchdirs;
    }
    void rewrite(const std::map<std::string, std::string>& rewritten_files);

private:
    void parse();
    void parse_slash_star_comment();
    void parse_pound_comment();
    void parse_input();
    void parse_group();
    void parse_as_needed();
    void parse_searchdir();
    void parse_startup();
    void parse_output_format();
    void parse_target();
    void parse_sections();
    std::pair<std::string, unsigned> parse_string();

    void chomp_whitespace() {
        int c;
        do {
            c = getc(m_file);
        } while (c != EOF && isspace(c));
        if (c != EOF)
          ungetc(c, m_file);
    }

    template<size_t len>
    void expect(const char (&s)[len]) {
        char temp[len];
        if (fgets(temp, len, m_file)) {
            if (strncmp(temp, s, len) == 0) {
                chomp_whitespace();
                return;
            } else {
                temp[len-1] = '\0';
                Error::printf("Could not parse linker script. Expected %s, found %s\n",
                              s, temp);
            }
        } else {
            Error::printf("Could not read enough characters. Expecting %s\n", s);
        }
    }

    template<size_t len>
    bool accept(const char (&s)[len]) {
        char temp[len];
        if (fgets(temp, len, m_file)) {
            if (strncmp(temp, s, len) == 0) {
                chomp_whitespace();
                return true;
            } else {
                fseek(m_file, -strlen(temp), SEEK_CUR);
            }
        }
        return false;
    }

    char peek() {
        char c = getc(m_file);
        if (c != EOF) {
            ungetc(c, m_file);
            return c;
        } else {
            return '\0';
        }
    }

    FILE *m_file;
    bool m_is_in_sysroot;
    const std::string &m_canonical_sysroot;

    std::vector<const char*> k_ignored_tokens = {
        "(", ")", ";", "+", "-", "*", ":", "{", "}", "/"
    };

    std::vector<std::pair<std::string, unsigned> > m_referenced_files;
    std::vector<std::string> m_searchdirs;
};

class LinkWrapper {
public:
    ~LinkWrapper();
    LinkerInvocation process(int argc, char *argv[]);

    std::string output_file() const {
        return m_output_file;
    }

private:
    void rewrite_file(std::string input_filename,
                      bool whole_archive,
                      bool script_in_sysroot,
                      ArgParser &Args);

    std::string m_temp_dir;
    std::pair<std::string, std::string> m_entry_points;
    std::map<std::string, std::string> m_rewritten_inputs;
    std::vector<std::string> m_temp_files;
    uint16_t m_elf_machine = EM_NONE;
    std::string m_output_file;
};

} // end namespace

int main(int argc, char* argv[]) {
    LinkWrapper wrapper;

    auto invocation = wrapper.process(argc, argv);
    auto &linker_args = std::get<0>(invocation);

    int linker_status = -1;
    if (!Misc::exec_child(linker_args.data(), &linker_status, false))
        Error::printf("Linker execution failed: %s\n", strerror(errno));

    if(linker_status) {
        Error::printf("Linker execution failed, status: %d\n", linker_status);
    } else {
        auto emitted_trap_info = std::get<1>(invocation);
        auto pic_warning = std::get<2>(invocation);
        if (emitted_trap_info && pic_warning) {
            auto output_file = wrapper.output_file();
            auto has_copy_relocs = ElfObject::has_copy_relocs(output_file.c_str());
            if (has_copy_relocs) {
                Error::printf("Output file '%s' has COPY relocations and might not run correctly; "
                              "to fix, recompile with -fPIC\n", output_file.c_str());
                linker_status = 1;
            }
        }
    }

    for (auto s : linker_args)
        free(s);

    return linker_status;
}

LinkWrapper::~LinkWrapper() {
#ifndef TRAPLINKER_KEEP_FILES
    for (auto filename : m_temp_files)
        Filesystem::remove(filename);
#endif
}

LinkerInvocation LinkWrapper::process(int argc, char* argv[]) {
    Debug::printf<3>("Temp dir: %s\n", m_temp_dir.c_str());

    ArgParser Args(argc, argv);

    if (!Args.parse()) {
        Error::printf("ERROR: Could not parse linker arguments\n");
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        Error::printf("ERROR: ELF library initialization failed\n");
    }

    m_entry_points = Args.get_entry_point_names();
    m_output_file = Args.output_file();

    // rewrite all input objects
    if (Args.is_trap_enabled()) {
        for (auto input_file : Args.input_files()) {
            rewrite_file(input_file.first, input_file.second, false, Args);
        }
    }

    auto linker_invocation =
        Args.create_new_invocation(m_rewritten_inputs, m_elf_machine);

    Debug::printf<2>("Invoking linker: ");
    for (char* s : std::get<0>(linker_invocation)) {
        Debug::printf<2>("%s ", s);
    }
    Debug::printf<2>("\n");

    std::get<0>(linker_invocation).push_back(0);

    return linker_invocation;
}

void LinkWrapper::rewrite_file(std::string input_filename,
                               bool whole_archive,
                               bool script_in_sysroot,
                               ArgParser &Args) {
    Debug::printf<1>("Processing file: %s\n", input_filename.c_str());
    if (m_rewritten_inputs.count(input_filename) != 0)
        return;

    int fd = open(input_filename.c_str(), O_RDONLY);
    if (fd == -1) {
#if 0
        // Scripts can contain non-absolute paths, which we just ignore (for
        // now)
        Error::printf("Could not open input file: %s\n", input_filename.c_str());
#endif
        return;
    }

    ObjectType type = parse_object_type(fd);
    if (type == SHARED_OBJECT || type == UNKNOWN) {
        close(fd);
        if (script_in_sysroot) {
            // Small hack: since we're moving the script out of
            // the given sysroot, we need to prepend the sysroot path
            // ourselves to every file (especially shared libraries);
            // we do this by forcing a rewrite from the file to itself
            m_rewritten_inputs[input_filename] = input_filename;
        }
        return;
    }

    // pair of descriptor, filename
    const char *temp_prefix = (type == STATIC_OBJECT) ? "trapobj" : "trapscript";
    auto temp_file = Filesystem::copy_to_temp_file(fd, temp_prefix, input_filename);
    m_temp_files.push_back(temp_file.second);
    close(fd);

    if (type == STATIC_OBJECT) {
        ElfObject obj(temp_file, m_entry_points);
        if (obj.needs_trap_info()) {
            Debug::printf<1>("Creating trap info for temp file: %s\n", temp_file.second.c_str());
            std::string rewritten_file;
            uint16_t file_machine;
            std::tie(rewritten_file, file_machine) = obj.create_trap_info(Args.emit_textramp(),
                                                                          Args.emit_eh_txtrp(),
                                                                          Args.ar_path());
            m_rewritten_inputs[input_filename] = rewritten_file;
            if (rewritten_file != temp_file.second)
                m_temp_files.push_back(rewritten_file);

            // Update the machine type
            if (file_machine != EM_NONE) {
                if (m_elf_machine == EM_NONE) {
                    m_elf_machine = file_machine;
                } else if (file_machine != m_elf_machine) {
                    Error::printf("Incompatible machine types:%hd and %hd\n",
                                  m_elf_machine, file_machine);
                }
            }
        }
    } else if (type == LINKER_SCRIPT) {
        // Determine whether this script resides in the sysroot,
        // so we can prepend the sysroot path to all referenced files
        script_in_sysroot = false;
        if (!Args.canonical_sysroot().empty()) {
            char *canonical_path = realpath(input_filename.c_str(), nullptr);
            if (canonical_path) {
                if (strncmp(canonical_path, Args.canonical_sysroot().c_str(),
                            Args.canonical_sysroot().length()) == 0)
                    script_in_sysroot = true;
                free(canonical_path);
            }
        }

        Debug::printf<2>("Parsing linker script %s\n", temp_file.second.c_str());
        LinkerScript script(temp_file.first, script_in_sysroot,
                            Args.canonical_sysroot());
        std::vector<std::string> referenced_files = script.referenced_files();
        for (auto file : referenced_files) {
            Debug::printf<2>("Found a file referenced from a linker script: %s\n", file.c_str());
            if (file[0] == '-' && file[1] == 'l') {
                // Script gave us a library in the form of -lNNN
                std::string lib_name = file.substr(2);
                std::string full_path;
                ArgParser::LibResult res = Args.find_library(lib_name, full_path);
                if (res == ArgParser::LibResult::FOUND_STATIC_LIB ||
                    res == ArgParser::LibResult::FOUND_SHARED_LIB) {
                    Debug::printf<2>("Found actual library file: %s\n", full_path.c_str());
                    file = full_path;
                }
            } else if (file[0] == '/') {
                if (script_in_sysroot) {
                    // If the script is in the sysroot, then all referenced
                    // files also need the sysroot path prepended
                    // (this is what gold does)
                    file = Args.canonical_sysroot() + file;
                }
            }
            rewrite_file(file, whole_archive, script_in_sysroot, Args);
        }
        script.rewrite(m_rewritten_inputs);
        m_rewritten_inputs[input_filename] = temp_file.second;
    }
    close(temp_file.first);
}

LinkerScript::LinkerScript(int fd, bool is_in_sysroot, const std::string &canonical_sysroot)
    : m_is_in_sysroot(is_in_sysroot), m_canonical_sysroot(canonical_sysroot) {
    m_file = fdopen(fd, "r+");
    parse();
}

void LinkerScript::parse() {
    Debug::printf<10>("Parsing a linker script\n");
    while (!feof(m_file)) {
        chomp_whitespace();
        // FIXME: this is very inefficient
        if (accept("/*"))
            parse_slash_star_comment();
        else if (accept("#"))
            parse_pound_comment();
        else if (accept("INCLUDE"))
            parse_string();
        else if (accept("INPUT"))
            parse_input();
        else if (accept("GROUP"))
            parse_group();
        else if (accept("SEARCH_DIR"))
            parse_searchdir();
        else if (accept("STARTUP"))
            parse_startup();
        else if (accept("OUTPUT_FORMAT"))
            parse_output_format();
        else if (accept("TARGET"))
            parse_target();
        else if (accept("SECTIONS"))
            parse_sections();
        else
            if (!parse_string().first.length())
              // If parse_string returns a zero length string
              // it's possible that a configure script passed
              // a solaris linker map file instead of a linker
              // script. Simply terminate with an error if so.
              Error::printf("Malformed linker script. Expected string, got %c\n", getc(m_file));
        chomp_whitespace();
    }
}

void LinkerScript::parse_slash_star_comment() {
    Debug::printf<10>("Parsing a comment\n");
    char cur;
    while ((cur = getc(m_file)) != EOF) {
        if (cur == '*' && peek() == '/') {
            fseek(m_file, 2, SEEK_CUR);
            break;
        }
    }
}

void LinkerScript::parse_pound_comment() {
    Debug::printf<10>("Parsing a comment\n");
    char cur;
    while ((cur = getc(m_file)) != EOF) {
        if (cur == '\n')
            break;
    }
}

void LinkerScript::parse_input() {
    Debug::printf<10>("Parsing INPUT\n");
    chomp_whitespace();
    expect("(");
    while (!accept(")")) {
        chomp_whitespace();
        if (accept("AS_NEEDED")) {
            parse_as_needed();
        } else {
            m_referenced_files.push_back(parse_string());
            accept(",");
        }
        chomp_whitespace();
    }
}

void LinkerScript::parse_group() {
    Debug::printf<10>("Parsing GROUP\n");
    chomp_whitespace();
    expect("(");
    chomp_whitespace();
    while (!accept(")")) {
        chomp_whitespace();
        if (accept("AS_NEEDED")) {
            parse_as_needed();
        } else {
            m_referenced_files.push_back(parse_string());
            accept(",");
        }
        chomp_whitespace();
    }
}

void LinkerScript::parse_as_needed() {
    Debug::printf<10>("Parsing AS_NEEDED\n");
    chomp_whitespace();
    expect("(");
    chomp_whitespace();
    while (!accept(")")) {
        m_referenced_files.push_back(parse_string());
        accept(",");
        chomp_whitespace();
    }
}

void LinkerScript::parse_searchdir() {
    expect("(");
    m_searchdirs.push_back(parse_string().first);
    expect(")");
}

void LinkerScript::parse_startup() {
    expect("(");
    m_referenced_files.push_back(parse_string());
    expect(")");
}

void LinkerScript::parse_output_format() {
    Debug::printf<10>("Parsing OUTPUT_FORMAT\n");
    expect("(");
    while (!accept(")")) {
        parse_string();
        accept(",");
    }
}

void LinkerScript::parse_target() {
    expect("(");
    parse_string();
    expect(")");
}

void LinkerScript::parse_sections() {
    Debug::printf<10>("Ignoring SECTIONS\n");
    chomp_whitespace();
    expect("{");
    int depth = 1;
    while (depth > 0) {
        int ch = getc(m_file);
        if (ch == '{') {
            depth++;
        } else if (ch == '}') {
            depth--;
        }
    }
    chomp_whitespace();
}

static inline bool is_script_string_char(char ch, bool first) {
    switch (ch) {
    // Alphanumerics
    case 'a' ... 'z':
    case 'A' ... 'Z':
    case '0' ... '9':
        return true;

    // Punctuation
    case '_':
    case '.':
    case '$':
    case '/':
    case '\\':
    case '~':
    case '[':
    case '*':
    case '-':
        return true;

    case ']':
    case '?':
    case '=':
    case '+':
    case ':':
        return !first;

    default:
        return false;
    }
}

std::pair<std::string, unsigned> LinkerScript::parse_string() {
    Debug::printf<10>("Parsing a string: ");
    long file_offset;
    char c;
    std::string s;
    chomp_whitespace();
    if (peek() == '"') {
        getc(m_file);
        file_offset = ftell(m_file);
        while ((c = getc(m_file)) != EOF) {
            if (c == '"')
                break;
            s += c;
        }
    } else {
        bool first = true;
        file_offset = ftell(m_file);
        while ((c = getc(m_file)) != EOF) {
            if (!is_script_string_char(c, first))
                break;
            s += c;
            first = false;
        }
        if (c != EOF)
            ungetc(c, m_file);
    }
    Debug::printf<10>("%s\n", s.c_str());
    chomp_whitespace();
    return std::make_pair(s, file_offset);
}

void LinkerScript::rewrite(const std::map<std::string, std::string>& rewritten_files) {
    // This assumes m_referenced_files is sorted in file order, which I think is accurate
    std::vector<char> out_buffer;
    off_t cur_offset = 0;
    fseek(m_file, 0, SEEK_END);
    off_t file_size = ftell(m_file);
    fseek(m_file, 0, SEEK_SET);
    for (auto file_ref : m_referenced_files) {
        auto file_path = file_ref.first;
        if (file_path[0] == '/' && m_is_in_sysroot)
            file_path = m_canonical_sysroot + file_path;
        if (rewritten_files.count(file_path) != 0) {
            off_t ref_offset = file_ref.second;
            off_t cur_buffer_offset = out_buffer.size();

            // Add more space
            out_buffer.resize(cur_buffer_offset+(ref_offset-cur_offset));

            // Copy in file between the end of the last reference and the start of the current one
            size_t bytes_read = fread(out_buffer.data()+cur_buffer_offset, 1, ref_offset-cur_offset, m_file);
            if (static_cast<off_t>(bytes_read) != ref_offset-cur_offset)
                Error::printf("Could not read enough data!\n");
            Debug::printf<10>("Copied %u bytes\n", bytes_read);
            cur_offset += bytes_read;

            // Write out the new filename
            out_buffer.insert(out_buffer.end(), rewritten_files.at(file_path).begin(),
                              rewritten_files.at(file_path).end());

            // Skip the old filename
            cur_offset += file_ref.first.size();
            fseek(m_file, file_ref.first.size(), SEEK_CUR);
        }
    }
    off_t cur_buffer_offset = out_buffer.size();
    out_buffer.resize(cur_buffer_offset+(file_size-cur_offset));
    size_t bytes_read = fread(out_buffer.data()+cur_buffer_offset, 1, file_size-cur_offset, m_file);
    if (static_cast<off_t>(bytes_read) != file_size-cur_offset)
        Error::printf("Could not read enough data! Tried to read %u bytes\n", file_size-cur_offset);

    fseek(m_file, 0, SEEK_SET);
    fwrite(out_buffer.data(), 1, out_buffer.size(), m_file);
    fflush(m_file);
    if(ftruncate(fileno(m_file), out_buffer.size()) == -1)
        perror("ftruncate");
}

bool ArgParser::parse() {
    // Print all args for debugging
    for (int i = 0; i < m_argc; ++i) {
        Debug::printf<3>("%s ", m_argv[i]);
    }
    Debug::printf<3>("\n");

    for (int i = 1; i < m_argc; ++i) {
        if (m_argv[i][0] == '-') {
            std::string arg = m_argv[i];
            std::string shortened_arg = arg;
            bool handled = false;

            auto equals_pos = arg.find("=");
            if (equals_pos != std::string::npos) {
                if (equals_pos <= 2) {
                    // single-character options cannot have --arg= form
                    Error::printf("Could not parse argument: %s\n", m_argv[i]);
                    return false;
                }
                shortened_arg = arg.substr(0, equals_pos);
            }

            auto arg_handler = m_arg_table.find(shortened_arg);
            if (arg_handler == m_arg_table.end() && shortened_arg.length() > 3) {
                // assuming the first character is a dash, search again with one
                // less dash, since both --arg and -arg are usually valid
                arg_handler = m_arg_table.find(shortened_arg.substr(1));
                if (arg_handler != m_arg_table.end())
                    shortened_arg = shortened_arg.substr(1);
            }

            // Handle single character args with no space
            if (arg_handler == m_arg_table.end() && arg.length() > 2) {
                arg_handler = m_arg_table.find(arg.substr(0, 2));
                if (arg_handler != m_arg_table.end())
                    shortened_arg = arg.substr(0, 2);
            }

            if (arg_handler != m_arg_table.end()) {
                int args_claimed = (this->*(arg_handler->second))(i, shortened_arg);
                if (args_claimed == -1)
                    return false;
                i += args_claimed;
                Debug::printf<3>("Parsed arg: %s, claiming %u args\n", shortened_arg.c_str(), args_claimed);
                handled = true;
                continue;
            }

            // slow path to deal with abbreviations...
            for (auto &arg_handler : m_arg_table) {
                if (arg.compare(0, arg.length(), arg_handler.first, 0, arg.length()) == 0
                    || (arg.length() > 3
                        && arg.compare(1, arg.length()-1, arg_handler.first, 0, arg.length()-1) == 0)) {
                    int args_claimed = (this->*(arg_handler.second))(i, arg_handler.first);
                    if (args_claimed == -1)
                        return false;
                    i += args_claimed;
                    handled = true;
                    break;
                }
            }

            if (!handled) {
                Debug::printf<3>("Couldn't parse arg: %s\n", arg.c_str());
                m_args.emplace_back(m_argv+i, 1);
            }
        } else {
            m_args.emplace_back(m_argv[i]);
            if (is_linker_replacement() || i >= 2)
                handle_input_file(i);
        }
    }

    // std::cout << "Output: " << m_output_file << '\n';
    // std::cout << "Input files: ";
    // for (auto input : m_input_files) {
    //     std::cout << input << ' ';
    // }
    // std::cout << '\n';
    // std::cout << "System libs:\n";
    // for (auto lib : m_system_libs) {
    //     std::cout << "    " << lib.first << ": " << lib.second << '\n';
    // }

    return true;
}

void ArgParser::change_option(std::string option, std::string value, bool single_arg) {
    const char *temp_args[2];
    temp_args[0] = value.c_str();
    for (auto &arg : m_args) {
        if (arg.is_option) {
            if (option == arg.arg) {
                if (single_arg)
                    arg.arg = temp_args[0];
                else
                    arg.value = temp_args[0];
                break;
            } else if (option.compare(arg.arg) == 0) {
                assert(single_arg);
                arg.arg = temp_args[0];
                break;
            }
        }
    }

    // if we didn't find the option, add it
    if (single_arg) {
        m_args.emplace_back((char * const *)temp_args, 1);
    } else {
        temp_args[0] = temp_args[1];
        temp_args[1] = option.c_str();
        m_args.emplace_back((char * const *)temp_args, 2);
    }
}

static std::string find_install_path() {
    ssize_t path_size = 1024;
    char *buffer = new char[path_size+1];
    ssize_t len = readlink("/proc/self/exe", buffer, path_size);
    if (len == 0) {
        perror("ERROR: Could not read /proc/self/exe:");
        delete[] buffer;
        return "";
    }
    if (len == path_size) {
        printf("ERROR: Current executable path is too long\n");
        delete[] buffer;
        return "";
    }
    buffer[len] = 0;
    char *path_str = dirname(buffer);
    std::string path(path_str, strlen(path_str));
    delete[] buffer;
    return path;
}

LinkerInvocation ArgParser::create_new_invocation(
    std::map<std::string, std::string> input_file_mapping,
    uint16_t elf_machine) {

    if (is_linker_replacement()) {
        char *executable_path;
        char *executable_name;
        if (!m_original_linker_path.empty()) {
            // User passed the path on the command line
            m_args.emplace(m_args.begin(), m_original_linker_path.c_str(), false);
        } else if ((executable_path = getenv(kLinkerPathVariable)) != nullptr) {
            m_args.emplace(m_args.begin(), executable_path, false);
        } else {
            executable_path = strdup(m_argv[0]);
            executable_name = basename(executable_path);
            m_args.emplace(m_args.begin(), executable_name, false);
            free(executable_path);
        }
    }

    // In --relocatable mode, we don't add TRaP info
    if (m_relocatable)
        m_enabled = false;
    // Building statically-linked shared libraries is wonky
    if (m_shared)
        m_static = false;
    // Statically-linked binary implies static libselfrando.a
    if (m_static)
        m_static_selfrando = true;

    // If TRaP mode is enabled, add all the arguments
    // If we couldn't determine the ELF machine, do not add TRaP info
    if (is_trap_enabled() && elf_machine != EM_NONE) {
        // Determine which linker we're running
        std::string randolib_install_path = find_install_path();
        std::string randolib_arch_install_path = randolib_install_path + "/"
            + kELFMachineNames.at(elf_machine);
        std::string linker_id_script = randolib_install_path + kLinkerIdScript;
        char *linker_id_args[] = { const_cast<char*>(linker_id_script.c_str()),
                                   const_cast<char*>(m_args.begin()->arg.c_str()),
                                   nullptr };
        int linker_type = 0;
        if (!Misc::exec_child(linker_id_args, &linker_type, true))
            Error::printf("Linker ID script execution failed: %s\n", strerror(errno));
        Debug::printf<2>("Linker type: %d\n", linker_type);

        // Prepend some arguments
        std::list<Arg>::iterator header_pos = std::next(m_args.begin());
        m_args.emplace(header_pos, strdup((std::string("-L") + randolib_install_path).c_str()), true);
        m_args.emplace(header_pos, strdup((std::string("-L") + randolib_arch_install_path).c_str()), true);

        // Add the files that mark the start of .txtrp
        m_args.emplace(header_pos, "--undefined=_TRaP_trap_begin", true);
        m_args.emplace(header_pos, "--whole-archive", true);
        if (m_selfrando_txtrp_pages) {
            m_args.emplace(header_pos, "-ltrapheader_page", true);
        } else {
            m_args.emplace(header_pos, "-ltrapheader", true);
        }
        m_args.emplace(header_pos, "--no-whole-archive", true);

        // Add other arguments to the end
        // First, add the selfrando libs (if enabled)
        if (m_add_selfrando_libs) {
            // Add both -init and --entry, since we don't know
            // which and in what order will be called
            if (m_hook_init) {
                change_option("-init=", std::string("-init=") + kInitEntryPointName, true);
            }
            if (m_hook_entry) {
                change_option("--entry=", std::string("--entry=") + kStartEntryPointName, true);
            }
            m_args.emplace(header_pos, strdup((std::string("--undefined=") + kInitEntryPointName).c_str()), true);
            m_args.emplace(header_pos, strdup((std::string("--undefined=") + kStartEntryPointName).c_str()), true);
            m_args.emplace(header_pos, strdup((std::string("--undefined=") + kTextrampAnchorName).c_str()), true);
            m_args.emplace(header_pos, "--whole-archive", true);
            if (m_shared) {
                m_args.emplace(header_pos, "-lrandoentry_so", true);
            } else {
                m_args.emplace(header_pos, "-lrandoentry_exec", true);
            }
            m_args.emplace(header_pos, "--no-whole-archive", true);

            std::string trap_script = randolib_install_path + kTrapScript;
            m_args.emplace_back("--whole-archive", true);
            m_args.emplace_back(trap_script.c_str(), true);
            m_args.emplace_back("-ltrapfooter", true);
            m_args.emplace_back("--no-whole-archive", true);
            if (m_static_selfrando && m_selfrando_txtrp_pages) {
                // WARNING: this must go after TrapFooter.o
                std::string selfrando_object = randolib_arch_install_path + kSelfrandoObject;
                m_args.emplace_back(selfrando_object.c_str(), true);
            } else if (m_static_selfrando) {
                m_args.emplace_back("--whole-archive", true);
                m_args.emplace_back("-l:libselfrando.a", true);
                m_args.emplace_back("--no-whole-archive", true);
            } else {
                m_args.emplace_back("-l:libselfrando.so", true);
            }
            if (!m_static && m_link_libdl) {
                // We can't pull in libdl.a for static builds,
                // since we haven't emitted TRaP info for it;
                // this fine for dynamically-linked builds, and not
                // a problem either for static builds since those
                // don't use `dl_iterate_phdr`
                m_args.emplace_back("-ldl", true);
            }
        }

        // Add the files that mark the end of .txtrp
        m_args.emplace_back("--whole-archive", true);
        if (m_static_selfrando && m_selfrando_txtrp_pages) {
            m_args.emplace_back("-ltrapfooter_page", true);
        } else {
            m_args.emplace_back("-ltrapfooter_nopage", true);
        }
        m_args.emplace_back("--no-whole-archive", true);
    } else {
        m_enabled = false;
    }

    std::vector<char*> new_args;
    for (auto arg : m_args) {
        Debug::printf<6>("Arg: %s %s\n", arg.arg.c_str(), arg.value.c_str());
        if (arg.is_option) {
            auto I = m_system_libs.find(arg);
            if (I != m_system_libs.end()) {
                auto J = input_file_mapping.find(I->second);
                if (J != input_file_mapping.end()) {
                    Debug::printf<6>("Adding rewritten system lib %s\n", J->second.c_str());
                    new_args.push_back(strdup(J->second.c_str()));
                    continue;
                }
            }
            new_args.push_back(strdup(arg.arg.c_str()));
            if (arg.value != "")
                new_args.push_back(strdup(arg.value.c_str()));
        } else {
            auto I = input_file_mapping.find(arg.arg);
            if (I != input_file_mapping.end()) {
                new_args.push_back(strdup(I->second.c_str()));
            } else {
                new_args.push_back(strdup(arg.arg.c_str()));
            }
        }
    }
    return std::make_tuple(new_args, m_enabled, m_pic_warning);
}

bool ArgParser::is_linker_replacement() {
    char *executable_path = strdup(m_argv[0]);
    char *executable_name = basename(executable_path);
    bool result = (strncmp(executable_name, kLinkerWrapperName, sizeof(kLinkerWrapperName)-1) != 0);
    free(executable_path);
    return result;
}

std::pair<std::string, std::string> ArgParser::get_entry_point_names() {
    return std::make_pair(m_dt_init, m_entry_point);
}

int ArgParser::get_value(int i, const std::string &arg_key, std::string &val) {
    std::string arg = m_argv[i];
    auto key_pos = arg.find(arg_key);
    auto after_key = key_pos + arg_key.length();
    assert(key_pos == 0 || key_pos == 1); // FIXME: are there other cases???
    if (after_key == arg.length()) {
        if (m_argc <= i+1)
            return -1;
        val = m_argv[i+1];
        return 1;
    } else {
        val = arg.substr(after_key);
        return 0;
    }
}

int ArgParser::handle_input_file(int i) {
    Debug::printf<3>("Found input file: %s\n", m_argv[i]);
    m_input_files.emplace_back(m_argv[i], m_whole_archive);
    return 1;
}

int ArgParser::handle_output(int i, const std::string &arg_key) {
    // FIXME: we should have short and long versions of this:
    // -o and --output=
    int args_claimed = get_value(i, arg_key, m_output_file);
    m_args.emplace_back(m_argv+i, args_claimed+1);
    return args_claimed;
}

int ArgParser::handle_entry(int i, const std::string &arg_key) {
    // FIXME: we should have short and long versions of this:
    // -e and --entry=
    int args_claimed = get_value(i, arg_key, m_entry_point);
    m_args.emplace_back(m_argv+i, args_claimed+1);
    return args_claimed;
}

int ArgParser::handle_init(int i, const std::string &arg_key) {
    // FIXME: this is actually a long option, so we need
    // to parse the '=' sign
    int args_claimed = get_value(i, arg_key, m_dt_init);
    m_args.emplace_back(m_argv+i, args_claimed+1);
    return args_claimed;
}

int ArgParser::handle_library(int i, const std::string &arg_key) {
    // FIXME: we should have short and long versions of this:
    // -l and --library=
    std::string lib_name;
    int args_claimed = get_value(i, arg_key, lib_name);
    if (args_claimed < 0)
        return args_claimed;

    Arg lib_arg(m_argv+i, args_claimed+1);
    if (m_system_libs.count(lib_arg) == 0) {
        std::string fullPath;
        LibResult res = find_library(lib_name, fullPath);
        if (res == FOUND_STATIC_LIB || res == FOUND_SHARED_LIB) {
            m_system_libs[lib_arg] = fullPath;
            m_input_files.emplace_back(fullPath, m_whole_archive);
        }
    }
    m_args.push_back(lib_arg);
    return args_claimed;
}

int ArgParser::handle_library_path(int i, const std::string &arg_key) {
    // FIXME: we should have short and long versions of this:
    // -L and --library-path=
    std::string path;
    int args_claimed = get_value(i, arg_key, path);
    if (args_claimed < 0)
        return args_claimed;

    m_args.emplace_back(m_argv+i, args_claimed+1);
    char *canonical_path = realpath(path.c_str(), nullptr);
    if (canonical_path) {
        m_library_paths.push_back(canonical_path);
        free(canonical_path);
    }
    return args_claimed;
}

int ArgParser::handle_shared(int i, const std::string &arg_key) {
    m_args.emplace_back(m_argv+i, 1);
    m_shared = true;
    return 0;
}

int ArgParser::handle_static(int i, const std::string &arg_key) {
    m_args.emplace_back(m_argv+i, 1);
    m_static = true;
    return 0;
}

int ArgParser::handle_dynamic(int i, const std::string &arg_key) {
    m_args.emplace_back(m_argv+i, 1);
    m_static = false;
    return 0;
}

int ArgParser::handle_relocatable(int i, const std::string &arg_key) {
    m_args.emplace_back(m_argv+i, 1);
    m_relocatable = true;
    return 0;
}

int ArgParser::handle_push_state(int i, const std::string &arg_key) {
    m_args.emplace_back(m_argv+i, 1);
    m_static_stack.push(m_static);
    return 0;
}

int ArgParser::handle_pop_state(int i, const std::string &arg_key) {
    m_args.emplace_back(m_argv+i, 1);
    if (!m_static_stack.empty()) {
        m_static = m_static_stack.top();
        m_static_stack.pop();
    }
    return 0;
}

int ArgParser::handle_z_keyword(int i, const std::string &arg_key) {
    std::string z_keyword;
    int args_claimed = get_value(i, arg_key, z_keyword);

    bool insert = false;
    if (z_keyword.length() > 2 &&
        z_keyword[0] == 'n' &&
        z_keyword[1] == 'o') {
        if (z_keyword == "nocombreloc") {
            m_z_keywords.erase("combreloc");
        } else if (z_keyword == "noexecstack") {
            m_z_keywords.erase("execstack");
        } else if (z_keyword == "norelro") {
            m_z_keywords.erase("relro");
        } else if (z_keyword == "notext") {
            m_z_keywords.erase("text");
        } else {
            insert = true;
        }
    } else {
        if (z_keyword == "textoff") {
            m_z_keywords.erase("text");
        } else {
            insert = true;
        }
    }
    if (insert)
        m_z_keywords.insert(z_keyword);

    m_args.emplace_back(m_argv+i, args_claimed+1);
    return args_claimed;
}

int ArgParser::handle_whole_archive(int i, const std::string &arg_key) {
    m_args.emplace_back(m_argv+i, 1);
    if (strncmp(m_argv[i], "--whole-archive", sizeof("--whole_archive")) == 0) {
        m_whole_archive = true;
    } else {
        m_whole_archive = false;
    }
    return 0;
}

int ArgParser::handle_sysroot(int i, const std::string &arg_key) {
    int args_claimed = get_value(i, arg_key, m_sysroot);
    m_args.emplace_back(m_argv+i, args_claimed+1);
    if (!m_sysroot.empty()) {
        // FIXME: get_value() should handle the '='
        if (m_sysroot[0] == '=')
            m_sysroot = m_sysroot.substr(1);
        char *canonical_path = realpath(m_sysroot.c_str(), nullptr);
        if (canonical_path) {
            m_canonical_sysroot = std::string(canonical_path);
            free(canonical_path);
        }
        Debug::printf<2>("Found sysroot: '%s'=>'%s'\n", m_sysroot.c_str(),
                         m_canonical_sysroot.c_str());
    }
    return args_claimed;
}

int ArgParser::handle_original_linker(int i, const std::string &arg_key) {
    int args_claimed = get_value(i, arg_key, m_original_linker_path);
    return args_claimed;
}

int ArgParser::handle_original_ar(int i, const std::string &arg_key) {
    int args_claimed = get_value(i, arg_key, m_original_ar_path);
    return args_claimed;
}

int ArgParser::handle_traplinker_disable(int i, const std::string &arg_key) {
    m_enabled = false;
    return 0;
}

int ArgParser::handle_traplinker_enable(int i, const std::string &arg_key) {
    m_enabled = true;
    return 0;
}

int ArgParser::ignore_arg(int i, const std::string &arg_key) {
    m_args.emplace_back(m_argv+i, 1);
    return 0;
}

int ArgParser::ignore_short_arg_with_value(int i, const std::string &arg_key) {
    std::string arg = m_argv[i];
    if (arg.length() > arg_key.length()) {
        m_args.emplace_back(m_argv+i, 1);
        return 0;
    } else if (m_argc <= i+1) {
        return -1;
    } else {
        m_args.emplace_back(m_argv+i, 2);
        return 1;
    }
}

int ArgParser::ignore_long_arg_with_value(int i, const std::string &arg_key) {
    auto equals_pos = std::string(m_argv[i]).find("=");
    if (equals_pos != std::string::npos) {
        m_args.emplace_back(m_argv+i, 1);
        return 0;
    } else {
        m_args.emplace_back(m_argv+i, 2);
        return 1;
    }
}

int ArgParser::ignore_arg_with_optional_value(int i, const std::string &arg_key) {
    auto equals_pos = std::string(m_argv[i]).find("=");
    if (equals_pos != std::string::npos) {
        m_args.emplace_back(m_argv+i, 1);
        return 0;
    } else {
        if (m_argc <= i+1 || m_argv[i+1][0] == '-') {
            m_args.emplace_back(m_argv+i, 1);
            return 0;
        } else {
            m_args.emplace_back(m_argv+i, 2);
            return 1;
        }
    }
}

int ArgParser::ignore_arg_disable_rando(int i, const std::string &arg_key) {
    m_args.emplace_back(m_argv+i, 1);
    m_enabled = false;
    return 0;
}

ArgParser::LibResult ArgParser::find_library(std::string &lib_name, std::string &full_path) {
    struct stat stat_buffer;
    for (auto &path : m_library_paths) {
        if (!m_static) {
            full_path = path + "/lib" + lib_name + ".so";
            if (stat(full_path.c_str(), &stat_buffer) == 0)
                return FOUND_SHARED_LIB;
        }
        full_path = path + "/lib" + lib_name + ".a";
        if (stat(full_path.c_str(), &stat_buffer) == 0)
            return FOUND_STATIC_LIB;
    }

    return NOT_FOUND;
}
