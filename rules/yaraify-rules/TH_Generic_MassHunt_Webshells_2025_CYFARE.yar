rule TH_Generic_MassHunt_Webshells_2025_CYFARE
{
    meta:
        author                       = "CYFARE"
        description                  = "Generic multi-language webshell mass-hunt rule (PHP/ASP(X)/JSP/Python/Perl/Node) - 2025"
        reference                    = "https://cyfare.net/"
        date                         = "2025-09-15"
        version                      = "1.0.0"
        yarahub_uuid                 = "c5a2bf1c-88a1-4b2a-8b3d-83b6f4b7f9e0"
        yarahub_license              = "CC0 1.0"
        yarahub_rule_matching_tlp    = "TLP:WHITE"
        yarahub_rule_sharing_tlp     = "TLP:WHITE"
        yarahub_reference_md5        = "d41d8cd98f00b204e9800998ecf8427e"

    strings:
        /* ------------------------------
           PHP indicators
        ------------------------------ */
        $php_tag1     = "<?php" ascii
        $php_tag2     = "<?= " ascii
        $php_super1   = /\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES)\b/ ascii nocase
        $php_super2   = "php://input" ascii nocase
        $php_super3   = "php://filter" ascii nocase

        /* exec/eval/load */
        $php_exec1    = /eval\s*\(/ ascii nocase
        $php_exec2    = /assert\s*\(/ ascii nocase
        $php_exec3    = /preg_replace\s*\([^)]{0,200}['"]\s*\/[^\/\r\n]{1,120}\/e\s*['"]\s*,/ ascii nocase
        $php_exec4    = /create_function\s*\(/ ascii nocase
        $php_exec5    = /include(_once)?\s*\(/ ascii nocase
        $php_exec6    = /require(_once)?\s*\(/ ascii nocase
        $php_exec7    = /call_user_func(_array)?\s*\(/ ascii nocase

        /* command/shell */
        $php_sys1     = /system\s*\(/ ascii nocase
        $php_sys2     = /shell_exec\s*\(/ ascii nocase
        $php_sys3     = /passthru\s*\(/ ascii nocase
        $php_sys4     = /exec\s*\(/ ascii nocase
        $php_sys5     = /popen\s*\(/ ascii nocase
        $php_sys6     = /proc_open\s*\(/ ascii nocase

        /* obfuscation/packing (fast atoms only) */
        $php_obf1     = /base64_decode\s*\(/ ascii nocase
        $php_obf2     = /gzinflate\s*\(/ ascii nocase
        $php_obf3     = /gzuncompress\s*\(/ ascii nocase
        $php_obf4     = /str_rot13\s*\(/ ascii nocase
        $php_obf5     = /strrev\s*\(/ ascii nocase
        $php_obf6     = /pack\s*\(/ ascii nocase
        $php_obf7     = /chr\s*\(/ ascii nocase
        /* high-signal combos replacing generic b64-blob scanning */
        $php_obf8     = /eval\s*\(\s*base64_decode\s*\(/ ascii nocase
        $php_obf9     = /gzinflate\s*\(\s*base64_decode\s*\(/ ascii nocase

        /* params/keys often seen in shells */
        $php_param1   = /(\b|"_?)(cmd|exec|pass|pwd|z0|z1|password)(=|["\]])/ ascii nocase
        $php_net1     = /fsockopen\s*\(/ ascii nocase
        $php_net2     = /curl_exec\s*\(/ ascii nocase

        /* ------------------------------
           ASP & ASPX indicators
        ------------------------------ */
        $asp_tag1     = "<%" ascii
        $asp_tag2     = /<%@\s*Page/ ascii nocase

        /* classic ASP eval/execute */
        $asp_exec1    = /Eval\s*\(/ ascii nocase
        $asp_exec2    = "Execute(" ascii nocase
        $asp_exec3    = "ExecuteGlobal" ascii

        /* .NET process/reflect/load */
        $asp_sys1     = "WScript.Shell" ascii
        $aspx_sys2    = "System.Diagnostics.ProcessStartInfo" ascii
        $aspx_sys3    = "Process.Start(" ascii
        $aspx_ref1    = "System.Reflection" ascii
        $aspx_ref2    = "Assembly.Load" ascii
        $aspx_ref3    = "AppDomain.CurrentDomain.Load" ascii

        /* obfuscation */
        $aspx_obf1    = "Convert.FromBase64String" ascii
        $aspx_obf2    = "FromBase64Transform" ascii
        $aspx_obf3    = "GZipStream" ascii

        /* request parameters */
        $asp_param1   = /Request\.(QueryString|Form|Item)\s*\[\s*"(cmd|exec|pass|pwd)"/ ascii nocase
        $asp_param2   = /Request\("(cmd|exec|pass|pwd)"\)/ ascii nocase

        /* ------------------------------
           JSP indicators
        ------------------------------ */
        $jsp_tag1     = "<%@" ascii
        $jsp_tag2     = "<%" ascii

        $jsp_sys1     = "Runtime.getRuntime().exec" ascii
        $jsp_sys2     = "new ProcessBuilder(" ascii
        $jsp_param1   = /request\.getParameter\(\s*"(cmd|exec|pass|pwd)"/ ascii nocase
        $jsp_obf1     = "Base64.getDecoder().decode" ascii
        $jsp_obf2     = "sun.misc.BASE64Decoder" ascii
        $jsp_mem1     = "ClassLoader.defineClass" ascii

        /* ------------------------------
           Python (CGI/simple handlers)
        ------------------------------ */
        $py_tag1      = "#!/usr/bin/env python" ascii nocase
        $py_tag2      = "#!/usr/bin/python" ascii nocase
        $py_tag3      = "import cgi" ascii nocase
        $py_tag4      = "from flask import request" ascii nocase

        $py_sys1      = "os.system(" ascii
        $py_sys2      = "os.popen(" ascii
        $py_sys3      = "subprocess.Popen(" ascii
        $py_shell     = "shell=True" ascii
        $py_param1    = "FieldStorage(" ascii
        $py_param2    = ".getvalue(" ascii
        $py_param3    = "request.args.get(" ascii
        $py_param4    = "request.form.get(" ascii
        $py_obf1      = "base64.b64decode(" ascii

        /* ------------------------------
           Perl (CGI)
        ------------------------------ */
        $pl_tag1      = "#!/usr/bin/perl" ascii
        $pl_tag2      = "use CGI" ascii
        $pl_sys1      = "system(" ascii
        $pl_sys2      = "qx/" ascii          // qx{} or qx// execution
        $pl_param1    = "param(" ascii
        $pl_param2    = "->param(" ascii
        $pl_obf1      = "MIME::Base64" ascii

        /* ------------------------------
           Node.js
        ------------------------------ */
        $node_tag1    = /require\(['"]http['"]\)/ ascii
        $node_cp1     = /require\(['"]child_process['"]\)/ ascii
        $node_exec1   = /child_process\.(exec|execSync|spawn)\s*\(/ ascii
        $node_param1  = /req\.(query|body)\.(cmd|exec|pass|pwd)/ ascii nocase
        $node_obf1    = /Buffer\.from\(.{0,64},\s*['"]base64['"]\)/ ascii

    condition:
        filesize < 2MB and
        (
            /* ---------- PHP ---------- */
            ( ($php_tag1 or $php_tag2) and
              (
                ( 1 of ($php_sys*) and 1 of ($php_super*) ) or
                ( ( 1 of ($php_exec*) or 1 of ($php_sys*) ) and 1 of ($php_obf*) and 1 of ($php_super*) ) or
                ( 2 of ($php_exec*) and 1 of ($php_param*) ) or
                ( 1 of ($php_net*)  and 1 of ($php_super*) and 1 of ($php_obf*) )
              )
            )
            or
            /* ---------- ASP / ASPX ---------- */
            ( ($asp_tag1 or $asp_tag2) and
              (
                ( 1 of ($asp_exec*) and 1 of ($asp_param*) ) or
                ( $asp_sys1 or 1 of ($aspx_sys*) ) or
                ( 1 of ($aspx_ref*) and 1 of ($aspx_obf*) )
              )
            )
            or
            /* ---------- JSP ---------- */
            ( ($jsp_tag1 or $jsp_tag2) and
              (
                ( 1 of ($jsp_sys*) and 1 of ($jsp_param*) ) or
                ( 1 of ($jsp_obf*) and ( 1 of ($jsp_sys*) or 1 of ($jsp_mem*) ) )
              )
            )
            or
            /* ---------- Python (CGI/simple) ---------- */
            ( ($py_tag1 or $py_tag2 or $py_tag3 or $py_tag4) and
              (
                ( 1 of ($py_sys*) and ( $py_shell or 1 of ($py_obf*) ) and 1 of ($py_param*) ) or
                ( 1 of ($py_sys*) and 1 of ($py_param*) )
              )
            )
            or
            /* ---------- Perl (CGI) ---------- */
            ( ($pl_tag1 or $pl_tag2) and
              (
                ( 1 of ($pl_sys*) and 1 of ($pl_param*) ) or
                ( 1 of ($pl_sys*) and $pl_obf1 )
              )
            )
            or
            /* ---------- Node.js ---------- */
            ( $node_tag1 and ( $node_cp1 or 1 of ($node_exec*) ) and
              ( $node_param1 or $node_obf1 )
            )
        )
}

